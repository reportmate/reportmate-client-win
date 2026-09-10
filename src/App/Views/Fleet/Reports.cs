using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Text.Json;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Fleet;

/// <summary>
/// The fleet reports, in the order the web app's Reports menu lists them. The Mac
/// client uses the same ids and order so the two apps stay tab for tab identical.
/// </summary>
public sealed record ReportArea(string Id, string Title, string Subtitle, Accent Accent)
{
    public static readonly IReadOnlyList<ReportArea> All =
    [
        new("installs", "Installs", "Managed software across the fleet", Accent.Emerald),
        new("applications", "Applications", "Installed versions and usage", Accent.Blue),
        new("system", "System", "Operating systems and updates", Accent.Purple),
        new("management", "Management", "Enrolment and policy", Accent.Yellow),
        new("identity", "Identity", "Accounts, groups and sign-in", Accent.Indigo),
        new("hardware", "Hardware", "Models, memory and storage", Accent.Orange),
        new("peripherals", "Peripherals", "Printers, displays and devices", Accent.Pink),
        new("security", "Security", "Protection status and findings", Accent.Red),
        new("network", "Network", "Connectivity and addressing", Accent.Teal),
    ];

    public static ReportArea? ById(string id) =>
        All.FirstOrDefault(a => string.Equals(a.Id, id, StringComparison.OrdinalIgnoreCase));
}

/// <summary>The Reports landing page: every report as a card, for narrow windows.</summary>
public sealed class ReportsPage : FleetPage
{
    /// <summary>Raised when a report card is chosen, so the shell can navigate.</summary>
    public static event Action<string>? ReportChosen;

    protected override Task<UIElement> BuildAsync()
    {
        var page = new StackPanel();
        page.Children.Add(Ui.TabHeader("Reports", "Fleet-wide views of every module", "", Accent.Blue));

        var grid = new UniformGrid { Columns = 3, Margin = new Thickness(0, 20, 0, 0) };
        foreach (var area in ReportArea.All)
        {
            var body = new StackPanel();
            body.Children.Add(Ui.Text(area.Title, "TitleTextStyle"));
            var sub = Ui.Caption(area.Subtitle);
            sub.TextWrapping = TextWrapping.Wrap;
            sub.Margin = new Thickness(0, 4, 0, 0);
            body.Children.Add(sub);

            var card = Ui.Card(body, new Thickness(18, 16, 18, 18));
            card.Margin = new Thickness(0, 0, 14, 14);
            card.Cursor = Cursors.Hand;
            var id = area.Id;
            card.MouseLeftButtonUp += (_, _) => ReportChosen?.Invoke(id);
            grid.Children.Add(card);
        }
        page.Children.Add(grid);
        return Task.FromResult<UIElement>(page);
    }
}

/// <summary>
/// One fleet report: the charted distributions across the top and a row per device
/// underneath, the same shape the web report pages use. The row content is driven by
/// the report's spec rather than hand-written per module.
/// </summary>
public sealed class ReportPage : FleetPage
{
    private readonly ReportArea _area;

    public ReportPage(ReportArea area) => _area = area;

    protected override async Task<UIElement> BuildAsync()
    {
        var page = new StackPanel();
        var spec = ReportSpec.For(_area.Id);
        if (spec is null)
        {
            page.Children.Add(Ui.TabHeader(_area.Title, _area.Subtitle, "", _area.Accent));
            page.Children.Add(Ui.Card(Ui.EmptyState($"No report is defined for {_area.Title.ToLowerInvariant()} yet.")));
            return page;
        }

        var result = await FleetApiClient.Instance.GetModuleAsync(spec.Module, spec.Limit);
        if (!result.Ok)
        {
            page.Children.Add(Ui.TabHeader(_area.Title, _area.Subtitle, "", _area.Accent));
            page.Children.Add(FleetUnavailable(result.Status, result.Detail));
            return page;
        }

        var rows = result.Data!;
        var capped = spec.Limit is { } cap && rows.Count >= cap;
        page.Children.Add(Ui.TabHeader(_area.Title, _area.Subtitle, "", _area.Accent,
            Ui.Caption(capped
                ? $"first {rows.Count:N0} {spec.RowNoun}"
                : $"{rows.Count:N0} {spec.RowNoun}")));

        if (rows.Count == 0)
        {
            page.Children.Add(Ui.Card(Ui.EmptyState($"No {_area.Title.ToLowerInvariant()} data has been reported.")));
            return page;
        }

        var distributions = BuildDistributions(spec, rows);
        if (distributions is not null) page.Children.Add(distributions);
        page.Children.Add(BuildTable(spec, rows));
        if (capped)
            page.Children.Add(Ui.Caption(
                $"Showing the first {rows.Count:N0} {spec.RowNoun}; the fleet holds more. "
                + "The figures above describe this page, not the whole fleet."));
        return page;
    }

    /// <summary>
    /// The widget row: how the fleet splits across each dimension the report charts.
    /// A dimension every device answers identically says nothing, so it is dropped.
    /// </summary>
    private static UIElement? BuildDistributions(ReportSpec spec, List<JsonElement> rows)
    {
        var cards = new List<UIElement>();
        foreach (var field in spec.Distributions)
        {
            var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var row in rows)
                foreach (var value in field.ReadAll(row).Distinct(StringComparer.OrdinalIgnoreCase))
                    counts[value] = counts.GetValueOrDefault(value) + 1;

            if (counts.Count < 2) continue;

            var total = counts.Values.Sum();
            var body = new StackPanel();
            foreach (var (name, count) in counts.OrderByDescending(kv => kv.Value).Take(6))
                body.Children.Add(Charts.Bar(name, count, total, Tone.Info));

            if (counts.Count > 6)
                body.Children.Add(Ui.Caption($"and {counts.Count - 6:N0} more"));

            cards.Add(Ui.StatBlock(field.Label, $"{counts.Count:N0} distinct", "", Accent.Blue, Pad(body)));
        }

        if (cards.Count == 0) return null;

        var grid = new UniformGrid { Columns = Math.Min(3, cards.Count), Margin = new Thickness(0, 20, 0, 0) };
        foreach (var card in cards)
        {
            if (card is FrameworkElement fe) fe.Margin = new Thickness(0, 0, 14, 14);
            grid.Children.Add(card);
        }
        return grid;
    }

    private static UIElement BuildTable(ReportSpec spec, List<JsonElement> rows)
    {
        var headers = spec.Columns.Select(c => c.Header).ToList();
        var data = rows.Select(row => new ReportRow(
            headers.Zip(spec.Columns.Select(c => c.Field.Read(row))).ToDictionary(p => p.First, p => p.Second)))
            .ToList();

        var columns = spec.Columns
            .Select(c => Col.Text(c.Header, $"[{c.Header}]", c.Width, star: c.Star, mono: c.Mono))
            .ToArray();

        var title = spec.Module switch
        {
            "hardware" => "Hardware Specifications",
            "applications" => "Applications",
            "installs" => "Managed Items",
            _ => "Devices",
        };
        var table = new FilteredTable<ReportRow>(title, "{0} of {1} " + spec.RowNoun,
            data, (r, q) => r.Matches(q), columns,
            $"Search {spec.RowNoun}...", $"No {spec.RowNoun} match the current filters")
            .Build();
        table.Margin = new Thickness(0, 6, 0, 0);
        return table;
    }

    private static UIElement Pad(UIElement body) =>
        new Border { Padding = new Thickness(20, 4, 20, 14), Child = body };
}

/// <summary>
/// A report row as the table sees it. The columns are decided by the report spec, so
/// the row is a bag of already-formatted strings addressed by header name.
/// </summary>
public sealed class ReportRow
{
    private readonly Dictionary<string, string> _values;
    private readonly string _haystack;

    public ReportRow(Dictionary<string, string> values)
    {
        _values = values;
        _haystack = string.Join(" ", values.Values);
    }

    /// <summary>Indexer so a column can bind with the path "[Header]".</summary>
    public string this[string header] => _values.GetValueOrDefault(header) ?? "";

    public bool Matches(string query) =>
        string.IsNullOrWhiteSpace(query) || _haystack.Contains(query, StringComparison.OrdinalIgnoreCase);
}
